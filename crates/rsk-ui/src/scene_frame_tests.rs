// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn pixels_on_the_exclusive_panel_boundaries_are_not_retained() {
    for point in [Point::new(240, 0), Point::new(0, 320)] {
        let mut scene = Scene::default();
        scene.draw_iter([Pixel(point, Rgb565::RED)]).unwrap();
        assert_eq!(scene.command_count(), 0, "{point:?}");
        assert_eq!(scene.error(), None);
    }
}

#[test]
fn a_complete_frame_forwards_its_viewport_clear_pixels_and_contiguous_raster() {
    let mut sink = DamageSink::filled(Rgb565::GREEN);
    {
        let mut frame = Frame::new(&mut sink);
        assert_eq!(
            frame.bounding_box(),
            Rectangle::new(Point::zero(), Size::new(240, 320))
        );
        frame.clear(Rgb565::BLUE).unwrap();
        frame
            .draw_iter([Pixel(Point::new(12, 13), Rgb565::RED)])
            .unwrap();
        frame
            .fill_contiguous(
                &Rectangle::new(Point::new(20, 20), Size::new(2, 1)),
                [Rgb565::GREEN, Rgb565::WHITE],
            )
            .unwrap();
    }
    assert_eq!(sink.canvas.pixel(12, 13), Rgb565::RED);
    assert_eq!(sink.canvas.pixel(20, 20), Rgb565::GREEN);
    assert_eq!(sink.canvas.pixel(21, 20), Rgb565::WHITE);
    assert_eq!(sink.canvas.pixel(22, 20), Rgb565::BLUE);
    assert_eq!(sink.canvas.pixel(0, 0), Rgb565::BLUE);
}

#[test]
fn a_damage_frame_forwards_a_pixel_without_replacing_its_neighbors() {
    let mut sink = DamageSink::filled(Rgb565::BLACK);
    {
        let mut frame = DamageFrame::new(&mut sink);
        frame
            .draw_iter([Pixel(Point::new(8, 8), Rgb565::RED)])
            .unwrap();
    }
    assert_eq!(sink.presentations, 1);
    assert_eq!(sink.rects, [Rect::new(8, 8, 1, 1)]);
    assert_eq!(sink.canvas.pixel(8, 8), Rgb565::RED);
    assert_eq!(
        sink.canvas
            .pixels
            .iter()
            .filter(|&&c| c != Rgb565::BLACK)
            .count(),
        1
    );
}
