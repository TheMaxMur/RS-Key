// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_full_long_run_spans_rows_without_spending_a_second_stream_token() {
    let mut scene = Scene::default();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::zero(), Size::new(240, 2)),
            core::iter::repeat_n(Rgb565::RED, 263),
        )
        .unwrap();
    assert_eq!(scene.command_count(), 1);
    assert_eq!(scene.stream_len, 17);
    assert_eq!(&scene.stream[15..17], &[7, 255]);
    assert_eq!(scene.error(), None);

    let mut canvas = Canvas::filled(Rgb565::BLACK);
    scene.replay(&mut canvas).unwrap();
    assert!(canvas.pixels[..263].iter().all(|&c| c == Rgb565::RED));
    assert!(canvas.pixels[263..].iter().all(|&c| c == Rgb565::BLACK));
}
