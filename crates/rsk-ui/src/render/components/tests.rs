// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use embedded_graphics::{
    Pixel,
    geometry::{OriginDimensions, Size},
};

struct Panel {
    pixels: std::vec::Vec<Rgb565>,
    fail: bool,
}

impl Panel {
    fn new() -> Self {
        Self {
            pixels: std::vec![theme::BG; usize::from(crate::PANEL_W) * usize::from(crate::PANEL_H)],
            fail: false,
        }
    }
    fn at(&self, x: u16, y: u16) -> Rgb565 {
        self.pixels[usize::from(y) * usize::from(crate::PANEL_W) + usize::from(x)]
    }
}

impl OriginDimensions for Panel {
    fn size(&self) -> Size {
        Size::new(u32::from(crate::PANEL_W), u32::from(crate::PANEL_H))
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = &'static str;
    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        if self.fail {
            return Err("panel refused");
        }
        for Pixel(at, color) in pixels {
            assert!((0..i32::from(crate::PANEL_W)).contains(&at.x));
            assert!((0..i32::from(crate::PANEL_H)).contains(&at.y));
            self.pixels[at.y as usize * usize::from(crate::PANEL_W) + at.x as usize] = color;
        }
        Ok(())
    }
}

#[test]
fn cards_keep_their_padding_and_render_title_rows_values_and_chevrons() {
    let mut panel = Panel::new();
    let height = card_h(true, 2);
    assert_eq!(height, 2 * PAD + 3 * ROW_H + ROW_GAP);
    assert_eq!(card_h(false, 0), 2 * PAD);
    card(&mut panel, 40, height).unwrap();
    assert_eq!(
        panel.at(crate::PANEL_W / 2, 40 + height / 2),
        theme::SURFACE
    );
    card_title(&mut panel, 40, Glyph::Key, "Passkeys").unwrap();
    card_row(&mut panel, 40, 0, Glyph::Globe, "Service", None).unwrap();
    card_row_chevron(
        &mut panel,
        40,
        1,
        Glyph::Lock,
        "PIN",
        Some(("Set", theme::ACCENT)),
    )
    .unwrap();
    assert!(panel.pixels.contains(&theme::ACCENT));
    assert!(panel.pixels.contains(&theme::TEXT));
    assert_eq!(panel.at(0, 100), theme::BG);
}

#[test]
fn arbitrary_rows_clip_long_labels_and_preserve_the_trailing_value() {
    for trailing in [None, Some(("Ready", theme::ACCENT))] {
        for chevron in [false, true] {
            let mut panel = Panel::new();
            let rect = Rect::new(6, 40, 228, 44);
            rect_card(&mut panel, rect).unwrap();
            rect_row(
                &mut panel,
                rect,
                Glyph::Key,
                "An unusually long display label that must be clipped",
                trailing,
                chevron,
            )
            .unwrap();
            assert_eq!(panel.at(0, 60), theme::BG);
            assert_eq!(panel.at(100, 100), theme::BG);
            assert!(panel.pixels.contains(&theme::TEXT));
            if trailing.is_some() {
                assert!(panel.pixels.contains(&theme::ACCENT));
            }
        }
    }
}

#[test]
fn an_empty_state_centers_its_icon_and_text_inside_the_card() {
    let mut panel = Panel::new();
    empty_state(&mut panel, 40, 150, Glyph::Key, "No passkeys").unwrap();
    assert!(panel.pixels.iter().any(|&color| color != theme::BG));
    assert_eq!(panel.at(0, 100), theme::BG);
    assert_eq!(panel.at(120, 220), theme::BG);
}

#[test]
fn every_component_propagates_a_panel_error() {
    let mut panel = Panel::new();
    panel.fail = true;
    let err = Err("panel refused");
    assert_eq!(card(&mut panel, 40, 100), err);
    assert_eq!(card_title(&mut panel, 40, Glyph::Key, "Keys"), err);
    assert_eq!(card_row(&mut panel, 40, 0, Glyph::Key, "Keys", None), err);
    assert_eq!(
        card_row_chevron(&mut panel, 40, 0, Glyph::Key, "Keys", None),
        err
    );
    assert_eq!(rect_card(&mut panel, Rect::new(6, 40, 228, 44)), err);
    assert_eq!(
        rect_row(
            &mut panel,
            Rect::new(6, 40, 228, 44),
            Glyph::Key,
            "Keys",
            None,
            false
        ),
        err
    );
    assert_eq!(empty_state(&mut panel, 40, 150, Glyph::Key, "Empty"), err);
}

#[test]
fn card_title_places_its_icon_and_heading_from_the_card_top() {
    let mut actual = crate::render::tests::Rec::new();
    card_title(&mut actual, 40, Glyph::Key, "Title").unwrap();
    let mut expected = crate::render::tests::Rec::new();
    let y = 40 + PAD;
    glyph::draw(
        &mut expected,
        Glyph::Key,
        Point::new(MARGIN + PAD, y),
        28,
        theme::ACCENT,
        theme::SURFACE,
    )
    .unwrap();
    text_left_on(
        &mut expected,
        "Title",
        EgPoint::new((MARGIN + PAD + 28 + 8) as i32, y as i32 + 20),
        font::Role::Heading,
        theme::TEXT,
        theme::SURFACE,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn card_row_places_icon_label_and_right_aligned_value() {
    let mut actual = crate::render::tests::Rec::new();
    card_row(
        &mut actual,
        40,
        1,
        Glyph::Lock,
        "Label",
        Some(("Val", theme::WARN)),
    )
    .unwrap();
    let mut expected = crate::render::tests::Rec::new();
    let row_idx = 1u16;
    let y = 40 + PAD + ROW_H + row_idx * (ROW_H + ROW_GAP);
    let x = MARGIN + PAD;
    glyph::draw(
        &mut expected,
        Glyph::Lock,
        Point::new(x, y),
        22,
        theme::MUTED,
        theme::SURFACE,
    )
    .unwrap();
    text_left_on(
        &mut expected,
        "Label",
        EgPoint::new((x + 22 + 8) as i32, y as i32 + 16),
        font::Role::Body,
        theme::TEXT,
        theme::SURFACE,
    )
    .unwrap();
    let w = font::width("Val", font::Role::Body).unwrap_or(0) as i32;
    text_on(
        &mut expected,
        "Val",
        EgPoint::new((PANEL_W - MARGIN - PAD) as i32 - w, y as i32 + 16),
        font::Role::Body,
        theme::WARN,
        theme::SURFACE,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn card_row_chevron_adds_the_chevron_after_the_shared_row() {
    let mut actual = crate::render::tests::Rec::new();
    card_row_chevron(&mut actual, 40, 1, Glyph::Lock, "Label", None).unwrap();
    let mut expected = crate::render::tests::Rec::new();
    card_row(&mut expected, 40, 1, Glyph::Lock, "Label", None).unwrap();
    let row_idx = 1u16;
    let y = 40 + PAD + ROW_H + row_idx * (ROW_H + ROW_GAP);
    glyph::draw(
        &mut expected,
        Glyph::Chevron,
        Point::new(PANEL_W - MARGIN - PAD - 14, y + (ROW_H - 14) / 2),
        14,
        theme::MUTED,
        theme::SURFACE,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn rect_row_places_its_icon_trailing_chevron_and_clipped_label() {
    let rect = Rect::new(16, 100, 208, 34);
    let mut actual = crate::render::tests::Rec::new();
    rect_row(
        &mut actual,
        rect,
        Glyph::Key,
        "A very long label that will not fit the clip area at all",
        Some(("1234567890", theme::WARN)),
        true,
    )
    .unwrap();
    let mut expected = crate::render::tests::Rec::new();
    let cy = rect.y as i32 + rect.h as i32 / 2;
    let gx = rect.x + 8;
    glyph::draw(
        &mut expected,
        Glyph::Key,
        Point::new(gx, (cy - 7) as u16),
        14,
        theme::GREY,
        theme::ROW_BG,
    )
    .unwrap();
    let mut right_x = rect.x as i32 + rect.w as i32 - 8;
    right_x -= 12;
    glyph::draw(
        &mut expected,
        Glyph::Chevron,
        Point::new(right_x as u16, (cy - 6) as u16),
        12,
        theme::MUTED,
        theme::ROW_BG,
    )
    .unwrap();
    let label_x = rect.x as i32 + 28;
    let tx = right_x - 4;
    font::right(
        &mut expected.clipped(&eg_rect(Rect::new(
            label_x as u16,
            rect.y,
            (tx - label_x).max(0) as u16,
            rect.h,
        ))),
        "1234567890",
        EgPoint::new(tx, cy),
        font::Role::Body,
        theme::WARN,
        theme::ROW_BG,
    )
    .unwrap();
    let label_right = tx - font::width("1234567890", font::Role::Body).unwrap_or(0) as i32 - 8;
    let clip = Rect::new(
        label_x as u16,
        rect.y,
        (label_right - label_x).max(0) as u16,
        rect.h,
    );
    text_left_ellipsized_on(
        &mut expected,
        "A very long label that will not fit the clip area at all",
        EgPoint::new(label_x, cy),
        font::Role::Body,
        theme::TEXT,
        theme::ROW_BG,
        clip,
        false,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);

    // The no-trailing branch places its label clip from right_x - 8.
    let mut actual = crate::render::tests::Rec::new();
    rect_row(
        &mut actual,
        rect,
        Glyph::Key,
        "A very long label that will not fit the clip area at all",
        None,
        true,
    )
    .unwrap();
    let mut expected = crate::render::tests::Rec::new();
    glyph::draw(
        &mut expected,
        Glyph::Key,
        Point::new(gx, (cy - 7) as u16),
        14,
        theme::GREY,
        theme::ROW_BG,
    )
    .unwrap();
    let chevron_x = rect.x as i32 + rect.w as i32 - 8 - 12;
    glyph::draw(
        &mut expected,
        Glyph::Chevron,
        Point::new(chevron_x as u16, (cy - 6) as u16),
        12,
        theme::MUTED,
        theme::ROW_BG,
    )
    .unwrap();
    let label_right = chevron_x - 8;
    let clip = Rect::new(
        label_x as u16,
        rect.y,
        (label_right - label_x).max(0) as u16,
        rect.h,
    );
    text_left_ellipsized_on(
        &mut expected,
        "A very long label that will not fit the clip area at all",
        EgPoint::new(label_x, cy),
        font::Role::Body,
        theme::TEXT,
        theme::ROW_BG,
        clip,
        false,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}

#[test]
fn empty_state_centres_its_glyph_and_text_in_the_card() {
    let mut actual = crate::render::tests::Rec::new();
    empty_state(&mut actual, 60, 120, Glyph::Key, "Nothing here").unwrap();
    let mut expected = crate::render::tests::Rec::new();
    let cy = 60 + 120 / 2;
    glyph::draw(
        &mut expected,
        Glyph::Key,
        Point::new((crate::PANEL_W as i32 / 2) as u16 - 18, cy - 30),
        36,
        theme::MUTED,
        theme::BG,
    )
    .unwrap();
    text(
        &mut expected,
        "Nothing here",
        EgPoint::new(crate::PANEL_W as i32 / 2, cy as i32 + 8),
        font::Role::Body,
        theme::MUTED,
    )
    .unwrap();
    assert_eq!(actual.px, expected.px);
    assert!(!actual.oob);
}
