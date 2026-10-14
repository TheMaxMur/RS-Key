// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn second_labels_keep_the_number_space_and_unit_at_representative_decimal_widths() {
    for (seconds, expected) in [(0, "0 s"), (30, "30 s"), (65535, "65535 s")] {
        assert_eq!(fmt_secs(seconds, &mut [0; 8]), expected);
    }
}

#[test]
fn a_count_label_uses_an_exactly_fitting_buffer_and_refuses_one_byte_less() {
    assert_eq!(fmt_count(2, "accounts", &mut [0; 10]), "2 accounts");
    assert_eq!(fmt_count(2, "accounts", &mut [0; 9]), "");
}

struct NoTransfers(usize);

impl OriginDimensions for NoTransfers {
    fn size(&self) -> Size {
        Size::new(PANEL_W.into(), PANEL_H.into())
    }
}

impl DrawTarget for NoTransfers {
    type Color = Rgb565;
    type Error = ();

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(&mut self, _pixels: I) -> Result<(), ()> {
        self.0 += 1;
        Err(())
    }
    fn fill_solid(&mut self, _area: &Rectangle, _color: Rgb565) -> Result<(), ()> {
        self.0 += 1;
        Err(())
    }
    fn fill_contiguous<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        _area: &Rectangle,
        _colors: I,
    ) -> Result<(), ()> {
        self.0 += 1;
        Err(())
    }
}

#[test]
fn unchanged_hold_progress_dispatches_no_drawing_operation() {
    let mut target = NoTransfers(0);
    assert_eq!(
        render_hold_fill(
            &mut target,
            Rect::new(14, 200, 212, 60),
            "Hold",
            5,
            5,
            10,
            theme::APPROVE
        ),
        Ok(())
    );
    assert_eq!(target.0, 0);
}

#[test]
fn a_hold_starting_at_the_panel_edge_blends_its_label_over_the_visible_wash() {
    let rect = Rect::new(0, 200, 120, 60);
    let mut actual = Rec::new();
    render_hold_button(&mut actual, rect, "Hold", theme::APPROVE).unwrap();
    render_hold_fill(&mut actual, rect, "Hold", 0, 5, 10, theme::APPROVE).unwrap();
    let mut expected = Rec::new();
    render_hold_button(&mut expected, rect, "Hold", theme::APPROVE).unwrap();
    render_hold_button(
        &mut expected.clipped(&eg_rect(Rect::new(0, 200, 60, 60))),
        rect,
        "Hold",
        theme::HOLD_ON_BLUE,
    )
    .unwrap();
    let difference = actual
        .px
        .iter()
        .zip(&expected.px)
        .enumerate()
        .find(|(_, (a, b))| a != b)
        .map(|(index, (a, b))| (index, *a, *b));
    assert_eq!(difference, None);
    assert!(!actual.oob);
}
