// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_pending_pixel_is_counted_and_replayed_before_it_is_flushed() {
    let mut scene = Scene::default();
    scene
        .draw_iter([Pixel(Point::new(12, 34), Rgb565::RED)])
        .unwrap();
    assert_eq!(scene.command_count(), 1);
    let mut canvas = Canvas::filled(Rgb565::BLACK);
    scene.replay(&mut canvas).unwrap();
    assert_eq!(canvas.pixels[34 * 240 + 12], Rgb565::RED);
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
fn a_valid_scene_can_use_the_last_complete_solid_record_in_the_stream() {
    let mut scene = Scene::default();
    for _ in 0..5 {
        scene
            .fill_contiguous(
                &Rectangle::new(Point::zero(), Size::new(240, 2)),
                core::iter::repeat_n(Rgb565::RED, 263),
            )
            .unwrap();
    }
    let solid = Rectangle::new(Point::new(10, 10), Size::new(1, 1));
    for _ in 0..1810 {
        scene.fill_solid(&solid, Rgb565::BLUE).unwrap();
    }
    assert_eq!(scene.stream_len, 16375);
    scene.fill_solid(&solid, Rgb565::GREEN).unwrap();
    assert_eq!(scene.stream_len, 16384);
    assert_eq!(scene.error(), None);
    let mut canvas = Canvas::filled(Rgb565::BLACK);
    scene.replay(&mut canvas).unwrap();
    assert_eq!(canvas.pixels[10 * 240 + 10], Rgb565::GREEN);
}

#[test]
fn an_overflow_palette_color_keeps_both_literal_bytes_in_replay() {
    let colors: Vec<Rgb565> = (0..32).map(|i| RawU16::new(0x0100 + i).into()).collect();
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::zero(), Size::new(32, 1)),
            colors.iter().copied(),
        )
        .unwrap();
    let mut canvas = Canvas::filled(Rgb565::BLACK);
    scene.replay(&mut canvas).unwrap();
    assert_eq!(&canvas.pixels[..32], colors);
    assert!(canvas.pixels[32..].iter().all(|&c| c == Rgb565::BLACK));
}

#[test]
fn a_short_palette_token_can_use_the_last_staging_byte() {
    let mut scene = Scene::default();
    let mut write = STREAM_CAPACITY - 1;
    assert_eq!(scene.finish_run(&mut write, Some(0), 0xF800, 7), Ok(()));
    assert_eq!(write, STREAM_CAPACITY);
    assert_eq!(scene.stream[STREAM_CAPACITY - 1], 6);
    assert_eq!(scene.command_count(), 1);
}

#[test]
fn a_long_palette_token_can_use_the_last_two_staging_bytes() {
    let mut scene = Scene::default();
    let mut write = STREAM_CAPACITY - 2;
    assert_eq!(scene.finish_run(&mut write, Some(0), 0xF800, 8), Ok(()));
    assert_eq!(write, STREAM_CAPACITY);
    assert_eq!(&scene.stream[STREAM_CAPACITY - 2..], &[7, 0]);
    assert_eq!(scene.command_count(), 1);
}

#[test]
fn a_literal_token_requires_room_for_both_color_bytes_before_writing() {
    let mut scene = Scene::default();
    let mut write = STREAM_CAPACITY - 1;
    assert_eq!(
        scene.finish_run(&mut write, None, 0xF800, 7),
        Err(SceneError::Capacity)
    );
    assert_eq!(write, STREAM_CAPACITY - 1);
    assert!(scene.stream.iter().all(|&b| b == 0));
    assert_eq!(scene.command_count(), 0);
    assert_eq!(scene.error(), Some(SceneError::Capacity));
}
